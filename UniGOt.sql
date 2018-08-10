USE [master]
GO
/****** Object:  Database [University]    Script Date: 8/10/2018 4:20:45 PM ******/
CREATE DATABASE [University]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'University', FILENAME = N'D:\Quy\SQLDATA\University.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB )
 LOG ON 
( NAME = N'University_log', FILENAME = N'D:\Quy\SQLDATA\University_log.ldf' , SIZE = 1024KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO
ALTER DATABASE [University] SET COMPATIBILITY_LEVEL = 120
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [University].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [University] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [University] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [University] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [University] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [University] SET ARITHABORT OFF 
GO
ALTER DATABASE [University] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [University] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [University] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [University] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [University] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [University] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [University] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [University] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [University] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [University] SET  DISABLE_BROKER 
GO
ALTER DATABASE [University] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [University] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [University] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [University] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [University] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [University] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [University] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [University] SET RECOVERY SIMPLE 
GO
ALTER DATABASE [University] SET  MULTI_USER 
GO
ALTER DATABASE [University] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [University] SET DB_CHAINING OFF 
GO
ALTER DATABASE [University] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [University] SET TARGET_RECOVERY_TIME = 0 SECONDS 
GO
ALTER DATABASE [University] SET DELAYED_DURABILITY = DISABLED 
GO
EXEC sys.sp_db_vardecimal_storage_format N'University', N'ON'
GO
ALTER DATABASE [University] SET QUERY_STORE = OFF
GO
USE [University]
GO
ALTER DATABASE SCOPED CONFIGURATION SET IDENTITY_CACHE = ON;
GO
ALTER DATABASE SCOPED CONFIGURATION SET LEGACY_CARDINALITY_ESTIMATION = OFF;
GO
ALTER DATABASE SCOPED CONFIGURATION FOR SECONDARY SET LEGACY_CARDINALITY_ESTIMATION = PRIMARY;
GO
ALTER DATABASE SCOPED CONFIGURATION SET MAXDOP = 0;
GO
ALTER DATABASE SCOPED CONFIGURATION FOR SECONDARY SET MAXDOP = PRIMARY;
GO
ALTER DATABASE SCOPED CONFIGURATION SET PARAMETER_SNIFFING = ON;
GO
ALTER DATABASE SCOPED CONFIGURATION FOR SECONDARY SET PARAMETER_SNIFFING = PRIMARY;
GO
ALTER DATABASE SCOPED CONFIGURATION SET QUERY_OPTIMIZER_HOTFIXES = OFF;
GO
ALTER DATABASE SCOPED CONFIGURATION FOR SECONDARY SET QUERY_OPTIMIZER_HOTFIXES = PRIMARY;
GO
USE [University]
GO
/****** Object:  Table [dbo].[Article]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Article](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Code] [varchar](255) NOT NULL,
	[Contents] [varchar](255) NOT NULL,
	[CreateDate] [datetime] NULL,
	[Description] [varchar](255) NULL,
	[Image] [varchar](255) NULL,
	[IsActive] [bit] NULL,
	[Title] [varchar](255) NOT NULL,
	[UniversityId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ArticleTag]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ArticleTag](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[ArticleId] [int] NULL,
	[MajorUniId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Block]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Block](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[BlockName] [varchar](255) NULL,
	[Description] [varchar](255) NULL,
	[IsActive] [bit] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[BlockMajorUniversity]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[BlockMajorUniversity](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NULL,
	[BLockId] [int] NOT NULL,
	[MajorUniversityID] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[BlockOfMajor]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[BlockOfMajor](
	[Id] [int] NOT NULL,
	[isActive] [bit] NULL,
	[BlockId] [int] NULL,
	[MajorId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Favorite]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Favorite](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[MajorUniversityId] [int] NULL,
	[UserId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[GroupMajor]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[GroupMajor](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NOT NULL,
	[Code] [varchar](10) NOT NULL,
	[Name] [varchar](50) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HighSchool]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HighSchool](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Code] [int] NOT NULL,
	[Name] [varchar](255) NOT NULL,
	[LocationId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Location]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Location](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NULL,
	[LocationCode] [varchar](255) NULL,
	[LocationName] [varchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Major]    Script Date: 8/10/2018 4:20:45 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Major](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Description] [varchar](255) NULL,
	[IsActive] [bit] NOT NULL,
	[MajorName] [varchar](255) NOT NULL,
	[GroupMajorId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MajorMBTI]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MajorMBTI](
	[Id] [int] NOT NULL,
	[isActive] [bit] NULL,
	[MajorId] [int] NULL,
	[MBTITypeID] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MajorUniversity]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MajorUniversity](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Description] [varchar](255) NULL,
	[isActive] [bit] NULL,
	[NumberOfYear] [float] NULL,
	[Prospects] [varchar](255) NULL,
	[Requirement] [varchar](255) NULL,
	[MajorId] [int] NULL,
	[UniversityId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MBTIGroup]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MBTIGroup](
	[Id] [int] NOT NULL,
	[isActive] [bit] NULL,
	[MBTIGroupName] [varchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MBTIQuestion]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MBTIQuestion](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Code] [varchar](255) NULL,
	[isActive] [bit] NULL,
	[Option1Name] [nvarchar](225) NULL,
	[Option2Name] [nvarchar](225) NULL,
	[QuestionContent] [nvarchar](225) NULL,
	[MBTIGroupId] [int] NULL,
 CONSTRAINT [PK__MBTIQues__3214EC073ADAF15D] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MBTIResult]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MBTIResult](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[TestDate] [datetime] NULL,
	[MBTITypeId] [int] NULL,
	[UserId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MBTIType]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MBTIType](
	[Id] [int] NOT NULL,
	[contentType] [varchar](255) NULL,
	[Description] [varchar](255) NULL,
	[isActive] [bit] NOT NULL,
	[MBTITypeName] [varchar](255) NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Provider]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Provider](
	[ProviderID] [varchar](255) NOT NULL,
	[ProviderName] [varchar](255) NOT NULL,
	[UserID] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[ProviderID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[QuestionAnswer]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[QuestionAnswer](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Contents] [varchar](255) NOT NULL,
	[Count] [int] NOT NULL,
	[CreatedDateTime] [datetime] NOT NULL,
	[IsActive] [bit] NOT NULL,
	[LastUpdatedTime] [datetime] NULL,
	[NumberOfReport] [int] NULL,
	[ParentId] [int] NOT NULL,
	[Status] [bit] NULL,
	[Title] [varchar](255) NULL,
	[Type] [int] NOT NULL,
	[Vote] [int] NULL,
	[UserId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[QuestionTag]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[QuestionTag](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[QuestionId] [int] NULL,
	[TagId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Report]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Report](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[QuestionAnswerId] [int] NULL,
	[UserId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Review]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Review](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Description] [varchar](255) NULL,
	[IsActive] [bit] NULL,
	[IsRecomment] [bit] NULL,
	[StarCare] [int] NULL,
	[StarCareer] [int] NULL,
	[StarFacilities] [int] NULL,
	[StarSocieties] [int] NULL,
	[StarTeaching] [int] NULL,
	[Status] [bit] NULL,
	[Title] [varchar](255) NULL,
	[UniversityId] [int] NOT NULL,
	[UserId] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReviewAverage]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReviewAverage](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[AveRecomment] [float] NOT NULL,
	[AveStarCare] [float] NOT NULL,
	[AveStarCareer] [float] NOT NULL,
	[AveStarFacilities] [float] NOT NULL,
	[AveStarSocieties] [float] NOT NULL,
	[AveStarTeaching] [float] NOT NULL,
	[TotalReview] [int] NOT NULL,
	[UniversityId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReviewLike]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReviewLike](
	[Id] [int] NOT NULL,
	[isActive] [bit] NULL,
	[IsLike] [bit] NULL,
	[ReviewId] [int] NULL,
	[UserId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReviewMajor]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReviewMajor](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NULL,
	[IsRecomment] [bit] NULL,
	[StarCareer] [int] NULL,
	[StarTeaching] [int] NULL,
	[MajorUniId] [int] NOT NULL,
	[UserId] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReviewMajorAverage]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReviewMajorAverage](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[AveRecomment] [float] NOT NULL,
	[AveStarCareer] [float] NOT NULL,
	[AveStarTeaching] [float] NOT NULL,
	[TotalReview] [int] NOT NULL,
	[MajorUniversityId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Role]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Role](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NOT NULL,
	[Name] [varchar](10) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ScoreHistory]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ScoreHistory](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Barem] [int] NULL,
	[Description] [varchar](255) NULL,
	[Score] [float] NULL,
	[Year] [int] NULL,
	[BlockMajorUniId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Tag]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Tag](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NOT NULL,
	[TagName] [varchar](255) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TrainSystem]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TrainSystem](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[IsActive] [bit] NOT NULL,
	[Name] [varchar](10) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[University]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[University](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Code] [varchar](255) NOT NULL,
	[Description] [varchar](255) NULL,
	[Email] [varchar](255) NULL,
	[Image] [varchar](255) NULL,
	[IsActive] [bit] NULL,
	[Logo] [varchar](255) NULL,
	[Name] [varchar](255) NOT NULL,
	[Phone] [varchar](255) NULL,
	[Priority] [int] NULL,
	[LocationId] [int] NULL,
	[TrainSystemId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Users]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Users](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Email] [varchar](255) NULL,
	[Image] [varchar](255) NULL,
	[IsActive] [bit] NOT NULL,
	[Name] [varchar](255) NULL,
	[Password] [varchar](255) NOT NULL,
	[Username] [varchar](50) NOT NULL,
	[HighSchoolId] [int] NULL,
	[RoleID] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Vote]    Script Date: 8/10/2018 4:20:46 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Vote](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[QuestionAnswerId] [int] NULL,
	[UserId] [int] NULL,
PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[Article] ON 

INSERT [dbo].[Article] ([Id], [Code], [Contents], [CreateDate], [Description], [Image], [IsActive], [Title], [UniversityId]) VALUES (3, N'AAA', N'ijk', CAST(N'2018-06-06T00:00:00.000' AS DateTime), N'asdr', N'ds', 1, N'sdcs', 3)
INSERT [dbo].[Article] ([Id], [Code], [Contents], [CreateDate], [Description], [Image], [IsActive], [Title], [UniversityId]) VALUES (4, N'BBB', N'dsjvhkxjkvjk', CAST(N'2018-05-05T00:00:00.000' AS DateTime), N'asdjnuf', N'sdscd', 0, N'czxa', 4)
INSERT [dbo].[Article] ([Id], [Code], [Contents], [CreateDate], [Description], [Image], [IsActive], [Title], [UniversityId]) VALUES (5, N'CCC', N'dwdqwrqwr`', CAST(N'2018-07-07T00:00:00.000' AS DateTime), N'asdxzscxz', N'xzcxcvxcv', 1, N'xzcwetw', 5)
INSERT [dbo].[Article] ([Id], [Code], [Contents], [CreateDate], [Description], [Image], [IsActive], [Title], [UniversityId]) VALUES (6, N'DDD', N'ojinimiomim', CAST(N'2018-04-04T00:00:00.000' AS DateTime), N'omimo', N'oimio', 0, N'mini', 6)
SET IDENTITY_INSERT [dbo].[Article] OFF
SET IDENTITY_INSERT [dbo].[ArticleTag] ON 

INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (1, 3, 5)
INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (2, 4, 6)
INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (3, 5, 7)
INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (4, 6, 8)
INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (5, 4, 7)
INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (6, 5, 5)
INSERT [dbo].[ArticleTag] ([Id], [ArticleId], [MajorUniId]) VALUES (7, 6, 8)
SET IDENTITY_INSERT [dbo].[ArticleTag] OFF
SET IDENTITY_INSERT [dbo].[Block] ON 

INSERT [dbo].[Block] ([Id], [BlockName], [Description], [IsActive]) VALUES (1, N'Block1', N'zxzxczx', 1)
INSERT [dbo].[Block] ([Id], [BlockName], [Description], [IsActive]) VALUES (2, N'Block2', N'ácdsf', 1)
INSERT [dbo].[Block] ([Id], [BlockName], [Description], [IsActive]) VALUES (3, N'Block3', N'asdasf', 0)
INSERT [dbo].[Block] ([Id], [BlockName], [Description], [IsActive]) VALUES (4, N'Block4', N'ekljerkt', 0)
SET IDENTITY_INSERT [dbo].[Block] OFF
SET IDENTITY_INSERT [dbo].[BlockMajorUniversity] ON 

INSERT [dbo].[BlockMajorUniversity] ([Id], [IsActive], [BLockId], [MajorUniversityID]) VALUES (9, 1, 1, 5)
INSERT [dbo].[BlockMajorUniversity] ([Id], [IsActive], [BLockId], [MajorUniversityID]) VALUES (10, 0, 2, 6)
INSERT [dbo].[BlockMajorUniversity] ([Id], [IsActive], [BLockId], [MajorUniversityID]) VALUES (11, 1, 3, 7)
INSERT [dbo].[BlockMajorUniversity] ([Id], [IsActive], [BLockId], [MajorUniversityID]) VALUES (12, 0, 4, 8)
SET IDENTITY_INSERT [dbo].[BlockMajorUniversity] OFF
INSERT [dbo].[BlockOfMajor] ([Id], [isActive], [BlockId], [MajorId]) VALUES (1, 1, 2, 4)
INSERT [dbo].[BlockOfMajor] ([Id], [isActive], [BlockId], [MajorId]) VALUES (2, 1, 3, 5)
INSERT [dbo].[BlockOfMajor] ([Id], [isActive], [BlockId], [MajorId]) VALUES (3, 1, 4, 6)
INSERT [dbo].[BlockOfMajor] ([Id], [isActive], [BlockId], [MajorId]) VALUES (4, 0, 1, 3)
INSERT [dbo].[BlockOfMajor] ([Id], [isActive], [BlockId], [MajorId]) VALUES (5, 1, 2, 5)
INSERT [dbo].[BlockOfMajor] ([Id], [isActive], [BlockId], [MajorId]) VALUES (6, 0, 3, 6)
SET IDENTITY_INSERT [dbo].[Favorite] ON 

INSERT [dbo].[Favorite] ([Id], [MajorUniversityId], [UserId]) VALUES (3, 5, 4)
INSERT [dbo].[Favorite] ([Id], [MajorUniversityId], [UserId]) VALUES (4, 6, 5)
INSERT [dbo].[Favorite] ([Id], [MajorUniversityId], [UserId]) VALUES (5, 7, 6)
INSERT [dbo].[Favorite] ([Id], [MajorUniversityId], [UserId]) VALUES (6, 8, 7)
SET IDENTITY_INSERT [dbo].[Favorite] OFF
SET IDENTITY_INSERT [dbo].[GroupMajor] ON 

INSERT [dbo].[GroupMajor] ([Id], [IsActive], [Code], [Name]) VALUES (1, 1, N'1', N'GM1')
INSERT [dbo].[GroupMajor] ([Id], [IsActive], [Code], [Name]) VALUES (2, 1, N'2', N'GM2')
INSERT [dbo].[GroupMajor] ([Id], [IsActive], [Code], [Name]) VALUES (3, 0, N'3', N'GM3')
INSERT [dbo].[GroupMajor] ([Id], [IsActive], [Code], [Name]) VALUES (4, 0, N'3', N'GM3')
INSERT [dbo].[GroupMajor] ([Id], [IsActive], [Code], [Name]) VALUES (5, 0, N'4', N'GM4')
SET IDENTITY_INSERT [dbo].[GroupMajor] OFF
SET IDENTITY_INSERT [dbo].[HighSchool] ON 

INSERT [dbo].[HighSchool] ([Id], [Code], [Name], [LocationId]) VALUES (1, 123, N'NCT', 1)
INSERT [dbo].[HighSchool] ([Id], [Code], [Name], [LocationId]) VALUES (2, 456, N'HHT', 2)
INSERT [dbo].[HighSchool] ([Id], [Code], [Name], [LocationId]) VALUES (3, 789, N'QQQ', 3)
INSERT [dbo].[HighSchool] ([Id], [Code], [Name], [LocationId]) VALUES (4, 159, N'FPT', 4)
INSERT [dbo].[HighSchool] ([Id], [Code], [Name], [LocationId]) VALUES (6, 547, N'SQA', 1)
SET IDENTITY_INSERT [dbo].[HighSchool] OFF
SET IDENTITY_INSERT [dbo].[Location] ON 

INSERT [dbo].[Location] ([Id], [IsActive], [LocationCode], [LocationName]) VALUES (1, 1, N'1', N'Location1')
INSERT [dbo].[Location] ([Id], [IsActive], [LocationCode], [LocationName]) VALUES (2, 0, N'2', N'Location2')
INSERT [dbo].[Location] ([Id], [IsActive], [LocationCode], [LocationName]) VALUES (3, 1, N'3', N'Location3')
INSERT [dbo].[Location] ([Id], [IsActive], [LocationCode], [LocationName]) VALUES (4, 0, N'4', N'Location4')
SET IDENTITY_INSERT [dbo].[Location] OFF
SET IDENTITY_INSERT [dbo].[Major] ON 

INSERT [dbo].[Major] ([Id], [Description], [IsActive], [MajorName], [GroupMajorId]) VALUES (3, N'Major1', 1, N'adas', 1)
INSERT [dbo].[Major] ([Id], [Description], [IsActive], [MajorName], [GroupMajorId]) VALUES (4, N'Major2', 1, N'asdasf', 2)
INSERT [dbo].[Major] ([Id], [Description], [IsActive], [MajorName], [GroupMajorId]) VALUES (5, N'Major3', 1, N'asdsgktj', 4)
INSERT [dbo].[Major] ([Id], [Description], [IsActive], [MajorName], [GroupMajorId]) VALUES (6, N'Major', 1, N'kmimn', 5)
INSERT [dbo].[Major] ([Id], [Description], [IsActive], [MajorName], [GroupMajorId]) VALUES (7, N'Mahor4', 1, N'cntt', 1)
SET IDENTITY_INSERT [dbo].[Major] OFF
INSERT [dbo].[MajorMBTI] ([Id], [isActive], [MajorId], [MBTITypeID]) VALUES (1, 1, 3, 1)
INSERT [dbo].[MajorMBTI] ([Id], [isActive], [MajorId], [MBTITypeID]) VALUES (2, 0, 4, 2)
INSERT [dbo].[MajorMBTI] ([Id], [isActive], [MajorId], [MBTITypeID]) VALUES (3, 1, 5, 3)
INSERT [dbo].[MajorMBTI] ([Id], [isActive], [MajorId], [MBTITypeID]) VALUES (4, 0, 6, 4)
SET IDENTITY_INSERT [dbo].[MajorUniversity] ON 

INSERT [dbo].[MajorUniversity] ([Id], [Description], [isActive], [NumberOfYear], [Prospects], [Requirement], [MajorId], [UniversityId]) VALUES (5, N'MajorU1', 1, 1, N'1', N'1', 3, 3)
INSERT [dbo].[MajorUniversity] ([Id], [Description], [isActive], [NumberOfYear], [Prospects], [Requirement], [MajorId], [UniversityId]) VALUES (6, N'MajorU2', 0, 1, N'1', N'1', 4, 4)
INSERT [dbo].[MajorUniversity] ([Id], [Description], [isActive], [NumberOfYear], [Prospects], [Requirement], [MajorId], [UniversityId]) VALUES (7, N'MajorU3', 1, 1, N'1', N'1', 5, 5)
INSERT [dbo].[MajorUniversity] ([Id], [Description], [isActive], [NumberOfYear], [Prospects], [Requirement], [MajorId], [UniversityId]) VALUES (8, N'MajorU4', 0, 2, N'2', N'2', 6, 6)
INSERT [dbo].[MajorUniversity] ([Id], [Description], [isActive], [NumberOfYear], [Prospects], [Requirement], [MajorId], [UniversityId]) VALUES (9, N'MajorU5', 1, 2, N'1', N'3', 4, 3)
SET IDENTITY_INSERT [dbo].[MajorUniversity] OFF
INSERT [dbo].[MBTIGroup] ([Id], [isActive], [MBTIGroupName]) VALUES (1, 1, N'1')
INSERT [dbo].[MBTIGroup] ([Id], [isActive], [MBTIGroupName]) VALUES (2, 0, N'2')
INSERT [dbo].[MBTIGroup] ([Id], [isActive], [MBTIGroupName]) VALUES (3, 1, N'3')
INSERT [dbo].[MBTIGroup] ([Id], [isActive], [MBTIGroupName]) VALUES (4, 0, N'4')
SET IDENTITY_INSERT [dbo].[MBTIQuestion] ON 

INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (1, N'A', 1, N'Xã hội , Giao tiếp', N'Thiết kế , ngiên cứu', N'Bạn thích công việc kiểu :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (2, N'A', 1, N'Khách Quan', N'Chủ Quan', N'Bạn tiếp xúc với một người theo xu hướng :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (3, N'A', 1, N'Ý nghĩa , giá trị', N'Tính logic', N'Bạn đánh giá sự việc dựa trên :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (4, N'A', 1, N'Thong thả , Thoải Mái', N'Nhanh nhẹn Đúng Giờ', N'Bạn là người có tác phong :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (5, N'A', 1, N'Bắt đầu cho cuộc nói chuyện', N'Chỉ nói khi người khác bắt chuyện', N'Trong các cuộc giao tiếp, bạn là người:', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (6, N'A', 1, N'Là người có cái đầu lạnh.', N' Là người có trái tim ấm.', N'Bạn là người thế nào :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (7, N'A', 1, N'Dễ chịu, thoải mái.', N'Nghiêm chỉnh, quả quyết.', N'Tính cách của bạn :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (8, N'A', 1, N'Khá thú vị', N'Khó hiểu.', N'Những người có tầm nhìn xa thường:', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (9, N'A', 1, N'Dễ dàng bắt chuyện và trò chuyện nhiều điều cùng họ.', N'Cảm thấy khó khăn và không biết nên nói gì.', N'Đối với những người mới gặp, bàn thường :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (10, N'A', 1, N'Không có quy trình cụ thể.', N'Thiếu tính sáng tạo.', N'Một công việc gây nhàm chán khi:', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (11, N'A', 1, N'Sự hòa hợp với mọi người.', N'Sự nhất quán trong suy nghĩ.', N'Bạn bị hấp dẫn bởi :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (12, N'A', 1, N'Giàu trí tưởng tượng.', N'Nắm bắt tình huống tốt.  ', N'Bạn bị lôi cuốn bởi kiểu người :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (13, N'A', 1, N'Dè dặt.', N'Thoải mái.', N'Trong các cuộc trò chuyện bạn thường :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (14, N'A', 1, N'Tuân theo chuẩn mực.', N'Đôi lúc không hiểu rõ nguyên nhân.', N'Lựa chọn của bạn có xu hướng :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (15, N'A', 1, N' Không công bằng.', N'Tàn nhẫn.', N'Trong hai điều sau, điều nào tồi tệ hơn:', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (16, N'A', 1, N'Kiên quyết.', N'Nhẹ nhàng.', N'Tính cách nào giống bạn hơn :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (17, N'A', 1, N'Độc lập giải quyết.', N'Trao đổi với mọi người.', N'Đối với một vấn đề trong nhóm :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (18, N'A', 1, N'Những điều bất ngờ không tính trước.', N'Những điều có kế hoặch trước.', N'Trong cuộc sống, bạn cảm thấy hứng thú với :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (19, N'A', 1, N' Chắc chắn trong tư tưởng.', N'Cống hiến hết mình.', N'Bạn thấy tâm đắc với bản thân bởi sự', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (20, N'A', 1, N'Khả năng lý luận phân tích.', N'Sự liên tưởng.', N'Bạn nhìn nhận một vấn đề với :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (21, N'A', 1, N'Ở nhà cùng gia đình.', N'Đi du lịch cùng bạn bè.', N'Trong các kỳ nghỉ lễ bạn có xu hướng :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (22, N'A', 1, N'Các ngụ ý, hàm ý, ẩn ý.', N'Các nguyên tắc, nguyên lý.', N'Bạn bị lôi cuốn bởi:', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (23, N'A', 1, N'Cảm nhận từ con tim.', N'Những quy tắc chung.', N'Khi quyết định việc gì bạn thường dựa vào :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (24, N'A', 1, N'Làm việc có phương pháp, tổ chức tốt.', N'Ứng biến xoay trở tốt trước khó khăn.', N'Bạn thích làm việc với người Sếp :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (25, N'A', 1, N'Sự chắc chắn.', N'Sự cởi mở.', N'Bạn nghiêng về :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (26, N'A', 1, N'Công tư phân minh.', N'Bị tình cảm chi phối.', N'Bạn là người có tư tưởng :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (27, N'A', 1, N'Nghệ thuật.', N'Khoa học.', N'Bạn thích học các môn :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (28, N'A', 1, N'Trầm lặng, ít nói.', N'Hoạt bát, vui vẻ.', N'Trong một nhóm bạn bè bạn thường :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (29, N'A', 1, N'Dựa vào vẻ ngoài của họ.', N'Dựa vào cảm nhận của bạn.', N'Khi đánh giá một người bạn thường :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (30, N'A', 1, N'Quá nồng nhiệt, mong chờ.', N'Quá khách quan.', N'Sẽ thật tai hại khi bạn :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (31, N'A', 1, N'Thích những thứ quen thuộc.', N'Thích những điều mới mẻ.', N'Phong cách của bạn :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (32, N'A', 1, N'Tìm kiếm một cách làm mới.', N'Làm theo cách mọi người hay làm.', N'Khi giải quyết một công việc thông thường, bạn sẽ :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (33, N'A', 1, N'Độc lập.', N'Theo nhóm.', N'Bạn thích làm việc :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (34, N'A', 1, N'Hiếm khi.', N'Hay xảy ra.', N'Bạn có hành động theo bản năng :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (35, N'A', 1, N'Giàu lý trí.', N'Giàu cảm xúc.', N'Trong cuộc sống, một người sẽ tốt hơn nếu :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (36, N'A', 1, N'Theo thứ tự.', N'Phát ngẫu nhiên.', N'Khi nghe một album nhạc mới, bạn thường nghe :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (37, N'A', 1, N'Khéo léo, lanh lợi.', N'Thẳng thắn, thực tế.', N'Bạn là người :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (38, N'A', 1, N'Sử dụng người khác.', N'Hiểu và chia sẻ với người khác.', N'Sẽ khó khăn hơn khi bạn cố:', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (39, N'A', 1, N'Diễn đạt trực tiếp nhất có thể.', N'Diễn đạt một cách gián tiếp.', N'Khi trình bày bạn thường :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (40, N'A', 1, N'Tìm bạn bè tâm sự hoặc đi chơi.', N'Muốn ở một mình cho khuây khỏa.', N'Khi cảm thấy buồn bạn thường :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (41, N'A', 1, N'Tham gia khi bị ép.', N'Năng nổ, tích cực.', N'Đối với các hoạt động của cơ quan, lớp học :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (42, N'A', 1, N'Những thứ không xác định.', N'Những thứ có logic.', N'Bạn cảm thấy thoái mái với :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (43, N'A', 1, N'Dễ dàng nắm bắt.', N'Giấu kín, khó nhận biết.', N'Cảm xúc của bạn thường được người khác :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (44, N'A', 1, N'Hành xử thiếu cân nhắc.', N'Chỉ trích, phê phán người khác.', N'Thật tồi tệ khi :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (45, N'A', 1, N'Chuẩn bị chu toàn trước.', N'Diễn ra tự nhiên.', N'Bạn muốn một sự kiện như thế nào :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (46, N'A', 1, N'Dễ gần, hòa đồng.', N'Thân thiện nhưng kín đáo.', N'Bạn là người có tình cách :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (47, N'A', 1, N'Trí tưởng tượng phong phú.', N'Sự quan sát thực tế.', N'Bạn có ưu điểm về :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (48, N'A', 1, N'Linh cảm.', N'Sự việc thực tế.', N'Khi quyết định điều gì đó, bạn tin vào :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (49, N'A', 1, N'Bạn là người có đầu óc suy luận.', N'Bạn là người giàu tình cảm và sự tinh tế.', N'Bạn muốn được người khác khen ngợi như thế nào :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (50, N'A', 1, N'Có chọn lựa và suy tính.', N'Một cách tự nhiên.', N'Bạn thích các sự việc xảy ra :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (51, N'A', 1, N'Bộc phát, linh hoạt.', N'Kỹ lưỡng, cẩn thận.', N'Bạn hay hành động một cách :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (52, N'A', 1, N'Tình cảm dồi dào.', N'Lý trí mạnh mẽ.', N'Bạn muốn bổ sung thêm điều gì ở bản thân :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (53, N'A', 1, N'Mơ mộng và tưởng tượng.', N'Thực tế và thực dụng.', N'Bạn là người :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (54, N'A', 1, N'Nhấc máy trước để nghe.', N'Để cho đồng nghiệp nhấc máy.', N'Khi điện thoại bàn trong văn phòng công ty đổ chuông :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (55, N'A', 1, N'Cố làm quen với nhiều người.', N'Chỉ nói chuyện với vài người.', N'Bạn mới tham gia một lớp Ngoại ngữ :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (56, N'A', 1, N'Bản thân nó giải thích cho chính nó.', N'Là bằng chứng giải thích cho các quy tắc, quy luật.', N'Theo bạn, các sự việc, sự kiện :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (57, N'A', 1, N'Đa sầu đa cảm.', N'Thực dụng, không bị chi phối bởi tình cảm.', N'Bạn là người :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (58, N'A', 1, N'Những suy nghĩ của họ.', N'Những gì họ làm được.', N'Bạn thường quan tâm tới người khác thông qua :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (59, N'A', 1, N'Thói quen.', N'Những điều mới mẻ.', N'Bạn nghiêng về điều nào sau đây :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (60, N'A', 1, N'Luôn được chuẩn bị kỹ lưỡng.', N'Tùy cơ ứng biến.', N'Mọi việc sẽ tôt hơn nếu :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (61, N'A', 1, N'Ít bạn nhưng chơi rất thân.', N'Nhiều bạn nhưng không thân thiết lắm.', N'Bạn thích mối quan hệ :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (62, N'A', 1, N'Diễn đạt lời văn qua các phép so sánh, ẩn dụ.', N'Nghĩ sao viết vậy, diễn đạt rõ ràng.', N'Nếu bạn là nhà văn, bạn sẽ viết bài theo cách :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (63, N'A', 1, N'Phụ thuộc vào tâm trạng.', N'Suy tính cẩn trọng.', N'Khi quyết định một việc :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (64, N'A', 1, N'Một cách chắn chắn.', N'Không chắc lắm, có thể thay đổi sau.', N'Bạn thường hay đưa ra quyết định :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (65, N'A', 1, N'Nguyên tắc, lý trí.', N'Cảm xúc, tình cảm.', N'Bạn là người sống thiên về :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (66, N'A', 1, N'Thực tế.', N'Bất ngờ, mới mẻ', N'Bạn thích thú với sự việc :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (67, N'A', 1, N'Không hứng thú.', N'Hào hứng.', N'Khi nói về một chủ đề mới lạ chưa gặp, bạn cảm thấy :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (68, N'A', 1, N'Kiểm tra lại trước khi áp dụng.', N'Tin tưởng và áp dụng theo.', N'Đối với một suy luận được nhiều người tin dùng, bạn sẽ :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (69, N'A', 1, N'Những thứ có tính logic cao.', N'Những thứ gây cảm động.', N'Điều gì làm cho bạn ấn tượng :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (70, N'A', 1, N'Những thứ thực tế và rõ ràng.', N'Những suy đoán.', N'Bạn là người có xu hướng thiên về :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (71, N'A', 1, N'Không thoải mái.', N'Thích thú.', N'Ở một nơi đông người làm bạn :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (72, N'A', 1, N'Hoàn cảnh nhất định.', N'Hoàn cảnh nhất định.', N'Bạn đánh giá một người dựa trên :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (73, N'A', 1, N'Ra về sớm vì không hào hứng lắm.', N'Vui chơi hết mình cho đến khi tàn tiệc.', N'Bạn được mời tới bữa tiệc của công ty :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (74, N'A', 1, N'Tuân thủ thời gian.', N'Làm việc tùy hứng.', N'Khi làm việc bạn sẽ :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (75, N'A', 1, N'Trò chuyện cùng nhiều người, quen hoặc không quen.', N'Chỉ trò chuyện với một số người quen.', N'Khi đi tham dự một buổi liên hoan/tiệc tùng, bạn sẽ :', 1)
INSERT [dbo].[MBTIQuestion] ([Id], [Code], [isActive], [Option1Name], [Option2Name], [QuestionContent], [MBTIGroupId]) VALUES (76, N'A', 1, N'Những thứ mơ hồ, không rõ ràng.', N'Những thứ nhàm chán, tẻ nhạt.', N'Điều gì làm bạn cảm thấy tồi tệ :', 1)
SET IDENTITY_INSERT [dbo].[MBTIQuestion] OFF
SET IDENTITY_INSERT [dbo].[MBTIResult] ON 

INSERT [dbo].[MBTIResult] ([Id], [TestDate], [MBTITypeId], [UserId]) VALUES (1, CAST(N'2018-07-10T00:00:00.000' AS DateTime), 1, 4)
INSERT [dbo].[MBTIResult] ([Id], [TestDate], [MBTITypeId], [UserId]) VALUES (2, CAST(N'2017-07-09T00:00:00.000' AS DateTime), 2, 5)
INSERT [dbo].[MBTIResult] ([Id], [TestDate], [MBTITypeId], [UserId]) VALUES (3, CAST(N'2018-08-07T00:00:00.000' AS DateTime), 3, 6)
INSERT [dbo].[MBTIResult] ([Id], [TestDate], [MBTITypeId], [UserId]) VALUES (4, CAST(N'2018-07-07T00:00:00.000' AS DateTime), 4, 7)
SET IDENTITY_INSERT [dbo].[MBTIResult] OFF
INSERT [dbo].[MBTIType] ([Id], [contentType], [Description], [isActive], [MBTITypeName]) VALUES (1, N'1', N'AAA', 1, N'MBT1')
INSERT [dbo].[MBTIType] ([Id], [contentType], [Description], [isActive], [MBTITypeName]) VALUES (2, N'2', N'BBB', 0, N'MBT2')
INSERT [dbo].[MBTIType] ([Id], [contentType], [Description], [isActive], [MBTITypeName]) VALUES (3, N'3', N'CCC', 1, N'MBT3')
INSERT [dbo].[MBTIType] ([Id], [contentType], [Description], [isActive], [MBTITypeName]) VALUES (4, N'4', N'DDD', 0, N'MBT4')
INSERT [dbo].[Provider] ([ProviderID], [ProviderName], [UserID]) VALUES (N'1', N'Pro1', 4)
INSERT [dbo].[Provider] ([ProviderID], [ProviderName], [UserID]) VALUES (N'109076235002763469215', N'google', 10)
INSERT [dbo].[Provider] ([ProviderID], [ProviderName], [UserID]) VALUES (N'2', N'Pro2', 5)
INSERT [dbo].[Provider] ([ProviderID], [ProviderName], [UserID]) VALUES (N'3', N'Pro3', 6)
INSERT [dbo].[Provider] ([ProviderID], [ProviderName], [UserID]) VALUES (N'4', N'Pro4', 7)
SET IDENTITY_INSERT [dbo].[QuestionAnswer] ON 

INSERT [dbo].[QuestionAnswer] ([Id], [Contents], [Count], [CreatedDateTime], [IsActive], [LastUpdatedTime], [NumberOfReport], [ParentId], [Status], [Title], [Type], [Vote], [UserId]) VALUES (2, N'AAAA', 1, CAST(N'2018-05-05T00:00:00.000' AS DateTime), 1, CAST(N'2018-05-05T00:00:00.000' AS DateTime), 10, 1, 1, N'czxzc', 1, 1, 4)
INSERT [dbo].[QuestionAnswer] ([Id], [Contents], [Count], [CreatedDateTime], [IsActive], [LastUpdatedTime], [NumberOfReport], [ParentId], [Status], [Title], [Type], [Vote], [UserId]) VALUES (3, N'BBBB', 2, CAST(N'2018-06-06T00:00:00.000' AS DateTime), 0, CAST(N'2018-06-06T00:00:00.000' AS DateTime), 12, 2, 0, N'zsczxq', 2, 2, 5)
INSERT [dbo].[QuestionAnswer] ([Id], [Contents], [Count], [CreatedDateTime], [IsActive], [LastUpdatedTime], [NumberOfReport], [ParentId], [Status], [Title], [Type], [Vote], [UserId]) VALUES (4, N'CCCC', 3, CAST(N'2018-07-07T00:00:00.000' AS DateTime), 1, CAST(N'2018-07-07T00:00:00.000' AS DateTime), 11, 8, 1, N'asdsc', 3, 3, 6)
INSERT [dbo].[QuestionAnswer] ([Id], [Contents], [Count], [CreatedDateTime], [IsActive], [LastUpdatedTime], [NumberOfReport], [ParentId], [Status], [Title], [Type], [Vote], [UserId]) VALUES (5, N'DDD', 4, CAST(N'2018-08-08T00:00:00.000' AS DateTime), 0, CAST(N'2018-08-08T00:00:00.000' AS DateTime), 6, 4, 0, N'ascdgw', 4, 4, 7)
SET IDENTITY_INSERT [dbo].[QuestionAnswer] OFF
SET IDENTITY_INSERT [dbo].[QuestionTag] ON 

INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (4, 2, 1)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (5, 3, 2)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (6, 4, 3)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (7, 5, 4)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (8, 2, 5)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (9, 3, 6)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (10, 2, 2)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (11, 4, 2)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (12, 5, 4)
INSERT [dbo].[QuestionTag] ([Id], [QuestionId], [TagId]) VALUES (13, 5, 3)
SET IDENTITY_INSERT [dbo].[QuestionTag] OFF
SET IDENTITY_INSERT [dbo].[Report] ON 

INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (4, 2, 4)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (5, 3, 5)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (6, 4, 6)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (7, 5, 7)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (8, 2, 7)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (9, 3, 4)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (10, 4, 7)
INSERT [dbo].[Report] ([Id], [QuestionAnswerId], [UserId]) VALUES (11, 3, 7)
SET IDENTITY_INSERT [dbo].[Report] OFF
SET IDENTITY_INSERT [dbo].[Review] ON 

INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (2, N'AAA', 1, 1, 1, 1, 1, 1, 1, 1, N'Re1', 3, 4)
INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (3, N'BBB', 0, 1, 2, 2, 2, 2, 2, 1, N'Re2', 4, 5)
INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (4, N'CCC', 1, 0, 3, 3, 3, 3, 3, 0, N'Re3', 5, 6)
INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (5, N'DDD', 1, 1, 8, 8, 8, 8, 8, 0, N'Re4', 6, 7)
INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (6, N'EEEE', 0, 0, 7, 7, 7, 7, 7, 1, N'Re5', 3, 5)
INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (7, N'GGG', 1, 1, 7, 7, 7, 7, 7, 1, N'Re6', 4, 6)
INSERT [dbo].[Review] ([Id], [Description], [IsActive], [IsRecomment], [StarCare], [StarCareer], [StarFacilities], [StarSocieties], [StarTeaching], [Status], [Title], [UniversityId], [UserId]) VALUES (8, N'HHH', 1, 1, 4, 4, 4, 4, 4, 1, N'Re7', 5, 5)
SET IDENTITY_INSERT [dbo].[Review] OFF
SET IDENTITY_INSERT [dbo].[ReviewAverage] ON 

INSERT [dbo].[ReviewAverage] ([Id], [AveRecomment], [AveStarCare], [AveStarCareer], [AveStarFacilities], [AveStarSocieties], [AveStarTeaching], [TotalReview], [UniversityId]) VALUES (3, 5, 5, 5, 5, 5, 5, 8, 3)
INSERT [dbo].[ReviewAverage] ([Id], [AveRecomment], [AveStarCare], [AveStarCareer], [AveStarFacilities], [AveStarSocieties], [AveStarTeaching], [TotalReview], [UniversityId]) VALUES (4, 6, 6, 6, 6, 6, 6, 7, 4)
INSERT [dbo].[ReviewAverage] ([Id], [AveRecomment], [AveStarCare], [AveStarCareer], [AveStarFacilities], [AveStarSocieties], [AveStarTeaching], [TotalReview], [UniversityId]) VALUES (5, 7, 8, 7, 4, 5, 8, 9, 5)
INSERT [dbo].[ReviewAverage] ([Id], [AveRecomment], [AveStarCare], [AveStarCareer], [AveStarFacilities], [AveStarSocieties], [AveStarTeaching], [TotalReview], [UniversityId]) VALUES (6, 8, 8, 8, 8, 8, 8, 8, 6)
INSERT [dbo].[ReviewAverage] ([Id], [AveRecomment], [AveStarCare], [AveStarCareer], [AveStarFacilities], [AveStarSocieties], [AveStarTeaching], [TotalReview], [UniversityId]) VALUES (7, 7, 7, 7, 8, 4, 5, 7, 4)
SET IDENTITY_INSERT [dbo].[ReviewAverage] OFF
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (1, 1, 1, 2, 4)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (2, 1, 1, 3, 5)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (3, 1, 1, 4, 6)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (4, 1, 1, 5, 7)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (5, 0, 0, 2, 5)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (6, 1, 0, 3, 4)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (7, 0, 1, 4, 4)
INSERT [dbo].[ReviewLike] ([Id], [isActive], [IsLike], [ReviewId], [UserId]) VALUES (8, 1, 0, 2, 6)
SET IDENTITY_INSERT [dbo].[ReviewMajor] ON 

INSERT [dbo].[ReviewMajor] ([Id], [IsActive], [IsRecomment], [StarCareer], [StarTeaching], [MajorUniId], [UserId]) VALUES (8, 1, 1, 1, 1, 5, 5)
INSERT [dbo].[ReviewMajor] ([Id], [IsActive], [IsRecomment], [StarCareer], [StarTeaching], [MajorUniId], [UserId]) VALUES (9, 1, 1, 2, 2, 6, 6)
INSERT [dbo].[ReviewMajor] ([Id], [IsActive], [IsRecomment], [StarCareer], [StarTeaching], [MajorUniId], [UserId]) VALUES (10, 0, 0, 3, 3, 7, 7)
INSERT [dbo].[ReviewMajor] ([Id], [IsActive], [IsRecomment], [StarCareer], [StarTeaching], [MajorUniId], [UserId]) VALUES (12, 0, 0, 4, 4, 8, 4)
INSERT [dbo].[ReviewMajor] ([Id], [IsActive], [IsRecomment], [StarCareer], [StarTeaching], [MajorUniId], [UserId]) VALUES (13, 1, 0, 3, 3, 7, 7)
INSERT [dbo].[ReviewMajor] ([Id], [IsActive], [IsRecomment], [StarCareer], [StarTeaching], [MajorUniId], [UserId]) VALUES (14, 0, 1, 2, 2, 6, 5)
SET IDENTITY_INSERT [dbo].[ReviewMajor] OFF
SET IDENTITY_INSERT [dbo].[ReviewMajorAverage] ON 

INSERT [dbo].[ReviewMajorAverage] ([Id], [AveRecomment], [AveStarCareer], [AveStarTeaching], [TotalReview], [MajorUniversityId]) VALUES (1, 8, 7, 7, 7, 7)
INSERT [dbo].[ReviewMajorAverage] ([Id], [AveRecomment], [AveStarCareer], [AveStarTeaching], [TotalReview], [MajorUniversityId]) VALUES (2, 9, 7, 8, 6, 6)
INSERT [dbo].[ReviewMajorAverage] ([Id], [AveRecomment], [AveStarCareer], [AveStarTeaching], [TotalReview], [MajorUniversityId]) VALUES (3, 6, 8, 7, 4, 5)
INSERT [dbo].[ReviewMajorAverage] ([Id], [AveRecomment], [AveStarCareer], [AveStarTeaching], [TotalReview], [MajorUniversityId]) VALUES (5, 7, 8, 6, 8, 8)
SET IDENTITY_INSERT [dbo].[ReviewMajorAverage] OFF
SET IDENTITY_INSERT [dbo].[Role] ON 

INSERT [dbo].[Role] ([Id], [IsActive], [Name]) VALUES (1, 1, N'Role1')
INSERT [dbo].[Role] ([Id], [IsActive], [Name]) VALUES (2, 0, N'Role2')
INSERT [dbo].[Role] ([Id], [IsActive], [Name]) VALUES (3, 1, N'Role3')
INSERT [dbo].[Role] ([Id], [IsActive], [Name]) VALUES (4, 0, N'Role4')
SET IDENTITY_INSERT [dbo].[Role] OFF
SET IDENTITY_INSERT [dbo].[ScoreHistory] ON 

INSERT [dbo].[ScoreHistory] ([Id], [Barem], [Description], [Score], [Year], [BlockMajorUniId]) VALUES (5, 1, N'SorceH1', 9, 2018, 9)
INSERT [dbo].[ScoreHistory] ([Id], [Barem], [Description], [Score], [Year], [BlockMajorUniId]) VALUES (6, 2, N'SorceH2', 8, 2017, 10)
INSERT [dbo].[ScoreHistory] ([Id], [Barem], [Description], [Score], [Year], [BlockMajorUniId]) VALUES (7, 3, N'SorceH3', 9, 2017, 11)
INSERT [dbo].[ScoreHistory] ([Id], [Barem], [Description], [Score], [Year], [BlockMajorUniId]) VALUES (8, 4, N'SorceH4', 10, 2014, 12)
SET IDENTITY_INSERT [dbo].[ScoreHistory] OFF
SET IDENTITY_INSERT [dbo].[Tag] ON 

INSERT [dbo].[Tag] ([Id], [IsActive], [TagName]) VALUES (1, 1, N'Tag1')
INSERT [dbo].[Tag] ([Id], [IsActive], [TagName]) VALUES (2, 0, N'Tag2')
INSERT [dbo].[Tag] ([Id], [IsActive], [TagName]) VALUES (3, 1, N'Tag3')
INSERT [dbo].[Tag] ([Id], [IsActive], [TagName]) VALUES (4, 0, N'Tag4')
INSERT [dbo].[Tag] ([Id], [IsActive], [TagName]) VALUES (5, 1, N'Tag5')
INSERT [dbo].[Tag] ([Id], [IsActive], [TagName]) VALUES (6, 1, N'Tag6')
SET IDENTITY_INSERT [dbo].[Tag] OFF
SET IDENTITY_INSERT [dbo].[TrainSystem] ON 

INSERT [dbo].[TrainSystem] ([Id], [IsActive], [Name]) VALUES (1, 1, N'Tran1')
INSERT [dbo].[TrainSystem] ([Id], [IsActive], [Name]) VALUES (2, 0, N'Tran2')
INSERT [dbo].[TrainSystem] ([Id], [IsActive], [Name]) VALUES (3, 1, N'Tran3')
INSERT [dbo].[TrainSystem] ([Id], [IsActive], [Name]) VALUES (4, 0, N'Tran4')
SET IDENTITY_INSERT [dbo].[TrainSystem] OFF
SET IDENTITY_INSERT [dbo].[University] ON 

INSERT [dbo].[University] ([Id], [Code], [Description], [Email], [Image], [IsActive], [Logo], [Name], [Phone], [Priority], [LocationId], [TrainSystemId]) VALUES (3, N'AHN', N'asdasd', N'sdsf', N'https://i2.cdn.turner.com/money/2010/08/30/news/economy/alabama_schools_bank_loans.fortune/lee_high.top.jpg', 1, N'http://niie.edu.vn/wp-content/uploads/2018/05/fpt-768x471.jpg', N'AAAAA', N'4545', 1, 1, 1)
INSERT [dbo].[University] ([Id], [Code], [Description], [Email], [Image], [IsActive], [Logo], [Name], [Phone], [Priority], [LocationId], [TrainSystemId]) VALUES (4, N'ASH', N'sdsgmk', N'zdfmk', N'https://i2.cdn.turner.com/money/2010/08/30/news/economy/alabama_schools_bank_loans.fortune/lee_high.top.jpg', 1, N'http://niie.edu.vn/wp-content/uploads/2018/05/fpt-768x471.jpg', N'sadsdgxcv', N'541021', 2, 2, 2)
INSERT [dbo].[University] ([Id], [Code], [Description], [Email], [Image], [IsActive], [Logo], [Name], [Phone], [Priority], [LocationId], [TrainSystemId]) VALUES (5, N'CKS', N'asvjmmi', N'dikvmim', N'https://i2.cdn.turner.com/money/2010/08/30/news/economy/alabama_schools_bank_loans.fortune/lee_high.top.jpg', 1, N'm,k', N'o,o', N'3545', 3, 3, 3)
INSERT [dbo].[University] ([Id], [Code], [Description], [Email], [Image], [IsActive], [Logo], [Name], [Phone], [Priority], [LocationId], [TrainSystemId]) VALUES (6, N'LOK', N'cmkvmi', N'dvmimi', N'http://ratopati.prixa.net/media/albums/537076949_umR0QGkErk.jpg', 1, N'ffdimi', N'mimi', N'87845', 4, 4, 4)
SET IDENTITY_INSERT [dbo].[University] OFF
SET IDENTITY_INSERT [dbo].[Users] ON 

INSERT [dbo].[Users] ([Id], [Email], [Image], [IsActive], [Name], [Password], [Username], [HighSchoolId], [RoleID]) VALUES (4, N'asd', N'asd', 1, N'User1', N'123', N'User1', 1, 1)
INSERT [dbo].[Users] ([Id], [Email], [Image], [IsActive], [Name], [Password], [Username], [HighSchoolId], [RoleID]) VALUES (5, N'qwe', N'qwe', 0, N'User2', N'123', N'User2', 2, 2)
INSERT [dbo].[Users] ([Id], [Email], [Image], [IsActive], [Name], [Password], [Username], [HighSchoolId], [RoleID]) VALUES (6, N'zxc', N'zxc', 1, N'User3', N'123', N'User3', 3, 3)
INSERT [dbo].[Users] ([Id], [Email], [Image], [IsActive], [Name], [Password], [Username], [HighSchoolId], [RoleID]) VALUES (7, N'frt', N'ftr', 0, N'User4', N'123', N'User4', 4, 4)
INSERT [dbo].[Users] ([Id], [Email], [Image], [IsActive], [Name], [Password], [Username], [HighSchoolId], [RoleID]) VALUES (10, N'quypcse62249@fpt.edu.vn', N'https://lh4.googleusercontent.com/-jgu3lbKzEXk/AAAAAAAAAAI/AAAAAAAAAAA/AAnnY7pK1A_mMdj5KL0_nUTZHYTuLtCUWQ/s96-c/photo.jpg', 1, N'Quy Pham Chanh', N'12345678', N'quypcse62249@fpt.edu.vn', NULL, 1)
SET IDENTITY_INSERT [dbo].[Users] OFF
SET IDENTITY_INSERT [dbo].[Vote] ON 

INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (2, 2, 4)
INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (3, 3, 5)
INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (4, 4, 6)
INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (5, 5, 7)
INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (6, 2, 5)
INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (7, 3, 7)
INSERT [dbo].[Vote] ([Id], [QuestionAnswerId], [UserId]) VALUES (8, 4, 4)
SET IDENTITY_INSERT [dbo].[Vote] OFF
ALTER TABLE [dbo].[Article]  WITH CHECK ADD  CONSTRAINT [FKmo1dhnc1v579su2ots5c9cost] FOREIGN KEY([UniversityId])
REFERENCES [dbo].[University] ([Id])
GO
ALTER TABLE [dbo].[Article] CHECK CONSTRAINT [FKmo1dhnc1v579su2ots5c9cost]
GO
ALTER TABLE [dbo].[ArticleTag]  WITH CHECK ADD  CONSTRAINT [FK9ka23sfw16dlc91doym7teo5a] FOREIGN KEY([MajorUniId])
REFERENCES [dbo].[MajorUniversity] ([Id])
GO
ALTER TABLE [dbo].[ArticleTag] CHECK CONSTRAINT [FK9ka23sfw16dlc91doym7teo5a]
GO
ALTER TABLE [dbo].[ArticleTag]  WITH CHECK ADD  CONSTRAINT [FKdq8n6fx6k0le144monv9fgbmy] FOREIGN KEY([ArticleId])
REFERENCES [dbo].[Article] ([Id])
GO
ALTER TABLE [dbo].[ArticleTag] CHECK CONSTRAINT [FKdq8n6fx6k0le144monv9fgbmy]
GO
ALTER TABLE [dbo].[BlockMajorUniversity]  WITH CHECK ADD  CONSTRAINT [FKhbhqrjhc0l8m7frq4bxr5n251] FOREIGN KEY([BLockId])
REFERENCES [dbo].[Block] ([Id])
GO
ALTER TABLE [dbo].[BlockMajorUniversity] CHECK CONSTRAINT [FKhbhqrjhc0l8m7frq4bxr5n251]
GO
ALTER TABLE [dbo].[BlockMajorUniversity]  WITH CHECK ADD  CONSTRAINT [FKtojafyp8ffurwafroqvpayfs1] FOREIGN KEY([MajorUniversityID])
REFERENCES [dbo].[MajorUniversity] ([Id])
GO
ALTER TABLE [dbo].[BlockMajorUniversity] CHECK CONSTRAINT [FKtojafyp8ffurwafroqvpayfs1]
GO
ALTER TABLE [dbo].[BlockOfMajor]  WITH CHECK ADD  CONSTRAINT [FK1br58v5jstrt3eud31a8sgyv8] FOREIGN KEY([MajorId])
REFERENCES [dbo].[Major] ([Id])
GO
ALTER TABLE [dbo].[BlockOfMajor] CHECK CONSTRAINT [FK1br58v5jstrt3eud31a8sgyv8]
GO
ALTER TABLE [dbo].[BlockOfMajor]  WITH CHECK ADD  CONSTRAINT [FK6299ybajyhmtj4yp4jhirv5vp] FOREIGN KEY([BlockId])
REFERENCES [dbo].[Block] ([Id])
GO
ALTER TABLE [dbo].[BlockOfMajor] CHECK CONSTRAINT [FK6299ybajyhmtj4yp4jhirv5vp]
GO
ALTER TABLE [dbo].[Favorite]  WITH CHECK ADD  CONSTRAINT [FKn090x5xhb8gjl7s1eui9kvm3e] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[Favorite] CHECK CONSTRAINT [FKn090x5xhb8gjl7s1eui9kvm3e]
GO
ALTER TABLE [dbo].[Favorite]  WITH CHECK ADD  CONSTRAINT [FKrk3rqr7t04vdm17ju5otuaqkm] FOREIGN KEY([MajorUniversityId])
REFERENCES [dbo].[MajorUniversity] ([Id])
GO
ALTER TABLE [dbo].[Favorite] CHECK CONSTRAINT [FKrk3rqr7t04vdm17ju5otuaqkm]
GO
ALTER TABLE [dbo].[HighSchool]  WITH CHECK ADD  CONSTRAINT [FKq9c7st28dl5vc2glkws50ftnd] FOREIGN KEY([LocationId])
REFERENCES [dbo].[Location] ([Id])
GO
ALTER TABLE [dbo].[HighSchool] CHECK CONSTRAINT [FKq9c7st28dl5vc2glkws50ftnd]
GO
ALTER TABLE [dbo].[Major]  WITH CHECK ADD  CONSTRAINT [FKd1k67uuvuf846cy3j3h21x8j6] FOREIGN KEY([GroupMajorId])
REFERENCES [dbo].[GroupMajor] ([Id])
GO
ALTER TABLE [dbo].[Major] CHECK CONSTRAINT [FKd1k67uuvuf846cy3j3h21x8j6]
GO
ALTER TABLE [dbo].[MajorMBTI]  WITH CHECK ADD  CONSTRAINT [FK4nmrhriaxyb2tgew75sxks0hd] FOREIGN KEY([MBTITypeID])
REFERENCES [dbo].[MBTIType] ([Id])
GO
ALTER TABLE [dbo].[MajorMBTI] CHECK CONSTRAINT [FK4nmrhriaxyb2tgew75sxks0hd]
GO
ALTER TABLE [dbo].[MajorMBTI]  WITH CHECK ADD  CONSTRAINT [FKgr0avqnjr6p63sybqdmdk0wtj] FOREIGN KEY([MajorId])
REFERENCES [dbo].[Major] ([Id])
GO
ALTER TABLE [dbo].[MajorMBTI] CHECK CONSTRAINT [FKgr0avqnjr6p63sybqdmdk0wtj]
GO
ALTER TABLE [dbo].[MajorUniversity]  WITH CHECK ADD  CONSTRAINT [FK8m1odgweofkd7qwuarrxebbw1] FOREIGN KEY([MajorId])
REFERENCES [dbo].[Major] ([Id])
GO
ALTER TABLE [dbo].[MajorUniversity] CHECK CONSTRAINT [FK8m1odgweofkd7qwuarrxebbw1]
GO
ALTER TABLE [dbo].[MajorUniversity]  WITH CHECK ADD  CONSTRAINT [FKbkd2o6cpws7ic9c1jh0rswmau] FOREIGN KEY([UniversityId])
REFERENCES [dbo].[University] ([Id])
GO
ALTER TABLE [dbo].[MajorUniversity] CHECK CONSTRAINT [FKbkd2o6cpws7ic9c1jh0rswmau]
GO
ALTER TABLE [dbo].[MBTIQuestion]  WITH CHECK ADD  CONSTRAINT [FKbhjyj7pvdleatj5obvgcrieej] FOREIGN KEY([MBTIGroupId])
REFERENCES [dbo].[MBTIGroup] ([Id])
GO
ALTER TABLE [dbo].[MBTIQuestion] CHECK CONSTRAINT [FKbhjyj7pvdleatj5obvgcrieej]
GO
ALTER TABLE [dbo].[MBTIResult]  WITH CHECK ADD  CONSTRAINT [FKf5ct0yodcuw19w5fq28f0wlt2] FOREIGN KEY([MBTITypeId])
REFERENCES [dbo].[MBTIType] ([Id])
GO
ALTER TABLE [dbo].[MBTIResult] CHECK CONSTRAINT [FKf5ct0yodcuw19w5fq28f0wlt2]
GO
ALTER TABLE [dbo].[MBTIResult]  WITH CHECK ADD  CONSTRAINT [FKt1apxjg9kdox0a5f46xeyx825] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[MBTIResult] CHECK CONSTRAINT [FKt1apxjg9kdox0a5f46xeyx825]
GO
ALTER TABLE [dbo].[Provider]  WITH CHECK ADD  CONSTRAINT [FK3fhul5218f9fp2f1i6g6idl8h] FOREIGN KEY([UserID])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[Provider] CHECK CONSTRAINT [FK3fhul5218f9fp2f1i6g6idl8h]
GO
ALTER TABLE [dbo].[QuestionAnswer]  WITH CHECK ADD  CONSTRAINT [FKjfkby03ajnm4toegfys3b9qh5] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[QuestionAnswer] CHECK CONSTRAINT [FKjfkby03ajnm4toegfys3b9qh5]
GO
ALTER TABLE [dbo].[QuestionTag]  WITH CHECK ADD  CONSTRAINT [FKepwb69i433v9ha83p0a1qegq6] FOREIGN KEY([QuestionId])
REFERENCES [dbo].[QuestionAnswer] ([Id])
GO
ALTER TABLE [dbo].[QuestionTag] CHECK CONSTRAINT [FKepwb69i433v9ha83p0a1qegq6]
GO
ALTER TABLE [dbo].[QuestionTag]  WITH CHECK ADD  CONSTRAINT [FKgjcx4rtx7ntjf6qaw9yeo0gu1] FOREIGN KEY([TagId])
REFERENCES [dbo].[Tag] ([Id])
GO
ALTER TABLE [dbo].[QuestionTag] CHECK CONSTRAINT [FKgjcx4rtx7ntjf6qaw9yeo0gu1]
GO
ALTER TABLE [dbo].[Report]  WITH CHECK ADD  CONSTRAINT [FK6stiy9qma5dhj7yyp29j3dl92] FOREIGN KEY([QuestionAnswerId])
REFERENCES [dbo].[QuestionAnswer] ([Id])
GO
ALTER TABLE [dbo].[Report] CHECK CONSTRAINT [FK6stiy9qma5dhj7yyp29j3dl92]
GO
ALTER TABLE [dbo].[Report]  WITH CHECK ADD  CONSTRAINT [FKafq3uyf4n6qvyrlfkps203sph] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[Report] CHECK CONSTRAINT [FKafq3uyf4n6qvyrlfkps203sph]
GO
ALTER TABLE [dbo].[Review]  WITH CHECK ADD  CONSTRAINT [FK8pn6ya44x8djuydyd0rneqegj] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[Review] CHECK CONSTRAINT [FK8pn6ya44x8djuydyd0rneqegj]
GO
ALTER TABLE [dbo].[Review]  WITH CHECK ADD  CONSTRAINT [FKtl3frq5v4i0xhnif76ocdhr7n] FOREIGN KEY([UniversityId])
REFERENCES [dbo].[University] ([Id])
GO
ALTER TABLE [dbo].[Review] CHECK CONSTRAINT [FKtl3frq5v4i0xhnif76ocdhr7n]
GO
ALTER TABLE [dbo].[ReviewAverage]  WITH CHECK ADD  CONSTRAINT [FKpq3fl1jnw5ceyshe8no8qqh2m] FOREIGN KEY([UniversityId])
REFERENCES [dbo].[University] ([Id])
GO
ALTER TABLE [dbo].[ReviewAverage] CHECK CONSTRAINT [FKpq3fl1jnw5ceyshe8no8qqh2m]
GO
ALTER TABLE [dbo].[ReviewLike]  WITH CHECK ADD  CONSTRAINT [FKd8sc25trge36yo9ik5ie59jq3] FOREIGN KEY([ReviewId])
REFERENCES [dbo].[Review] ([Id])
GO
ALTER TABLE [dbo].[ReviewLike] CHECK CONSTRAINT [FKd8sc25trge36yo9ik5ie59jq3]
GO
ALTER TABLE [dbo].[ReviewLike]  WITH CHECK ADD  CONSTRAINT [FKeubxp6h29d4320thm5qyx4n5s] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[ReviewLike] CHECK CONSTRAINT [FKeubxp6h29d4320thm5qyx4n5s]
GO
ALTER TABLE [dbo].[ReviewMajor]  WITH CHECK ADD  CONSTRAINT [FK6baw6a2vct3nk5n44ei4hqc7y] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[ReviewMajor] CHECK CONSTRAINT [FK6baw6a2vct3nk5n44ei4hqc7y]
GO
ALTER TABLE [dbo].[ReviewMajor]  WITH CHECK ADD  CONSTRAINT [FKqlb1pm06xd6qxk44yat07najk] FOREIGN KEY([MajorUniId])
REFERENCES [dbo].[MajorUniversity] ([Id])
GO
ALTER TABLE [dbo].[ReviewMajor] CHECK CONSTRAINT [FKqlb1pm06xd6qxk44yat07najk]
GO
ALTER TABLE [dbo].[ReviewMajorAverage]  WITH CHECK ADD  CONSTRAINT [FKd7safbn153e348e7ejgpnxw1u] FOREIGN KEY([MajorUniversityId])
REFERENCES [dbo].[MajorUniversity] ([Id])
GO
ALTER TABLE [dbo].[ReviewMajorAverage] CHECK CONSTRAINT [FKd7safbn153e348e7ejgpnxw1u]
GO
ALTER TABLE [dbo].[ScoreHistory]  WITH CHECK ADD  CONSTRAINT [FK853e6si7uyli7aremfcdx0c1k] FOREIGN KEY([BlockMajorUniId])
REFERENCES [dbo].[BlockMajorUniversity] ([Id])
GO
ALTER TABLE [dbo].[ScoreHistory] CHECK CONSTRAINT [FK853e6si7uyli7aremfcdx0c1k]
GO
ALTER TABLE [dbo].[University]  WITH CHECK ADD  CONSTRAINT [FK8yht6iofa42oox0qod4x8eocr] FOREIGN KEY([TrainSystemId])
REFERENCES [dbo].[TrainSystem] ([Id])
GO
ALTER TABLE [dbo].[University] CHECK CONSTRAINT [FK8yht6iofa42oox0qod4x8eocr]
GO
ALTER TABLE [dbo].[University]  WITH CHECK ADD  CONSTRAINT [FKscy503mjibxor51f669y23vai] FOREIGN KEY([LocationId])
REFERENCES [dbo].[Location] ([Id])
GO
ALTER TABLE [dbo].[University] CHECK CONSTRAINT [FKscy503mjibxor51f669y23vai]
GO
ALTER TABLE [dbo].[Users]  WITH CHECK ADD  CONSTRAINT [FK98ltbnnq69up18kfeilxjkhck] FOREIGN KEY([RoleID])
REFERENCES [dbo].[Role] ([Id])
GO
ALTER TABLE [dbo].[Users] CHECK CONSTRAINT [FK98ltbnnq69up18kfeilxjkhck]
GO
ALTER TABLE [dbo].[Users]  WITH CHECK ADD  CONSTRAINT [FKgqe15n3e71m26d2s97cfayxf6] FOREIGN KEY([HighSchoolId])
REFERENCES [dbo].[HighSchool] ([Id])
GO
ALTER TABLE [dbo].[Users] CHECK CONSTRAINT [FKgqe15n3e71m26d2s97cfayxf6]
GO
ALTER TABLE [dbo].[Vote]  WITH CHECK ADD  CONSTRAINT [FKodekqw2k07fh1e516bgu9s9s4] FOREIGN KEY([UserId])
REFERENCES [dbo].[Users] ([Id])
GO
ALTER TABLE [dbo].[Vote] CHECK CONSTRAINT [FKodekqw2k07fh1e516bgu9s9s4]
GO
ALTER TABLE [dbo].[Vote]  WITH CHECK ADD  CONSTRAINT [FKp31ymwpob4v1c2prdu5281elp] FOREIGN KEY([QuestionAnswerId])
REFERENCES [dbo].[QuestionAnswer] ([Id])
GO
ALTER TABLE [dbo].[Vote] CHECK CONSTRAINT [FKp31ymwpob4v1c2prdu5281elp]
GO
USE [master]
GO
ALTER DATABASE [University] SET  READ_WRITE 
GO
