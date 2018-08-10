package com.unistart.entities;
// Generated Oct 1, 2017 10:03:30 PM by Hibernate Tools 4.3.1.Final

import java.io.Serializable;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Mbtiquestion generated by hbm2java
 */
@Entity
@Table(name = "MBTIQuestion", schema = "dbo", catalog = "University")
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Mbtiquestion implements Serializable {

	private Integer id;
	private Mbtigroup mbtigroup;
	private String code;
	private String questionContent;
	private String option1name;
	private String option2name;
	private Boolean isActive;

	public Mbtiquestion() {
	}

	public Mbtiquestion(Integer id) {
		this.id = id;
	}

	public Mbtiquestion(Integer id, Mbtigroup mbtigroup, String code, String questionContent,
			String option1name, String option2name, Boolean isActive) {
		this.id = id;
		this.mbtigroup = mbtigroup;
		this.code = code;
		this.questionContent = questionContent;
		this.option1name = option1name;
		this.option2name = option2name;
		this.isActive = isActive;
	}

	@Id

	@Column(name = "Id", unique = true, nullable = false)
	public Integer getId() {
		return this.id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "MBTIGroupId")
	public Mbtigroup getMbtigroup() {
		return this.mbtigroup;
	}

	public void setMbtigroup(Mbtigroup mbtigroup) {
		this.mbtigroup = mbtigroup;
	}

	@Column(name = "Code")
	public String getCode() {
		return this.code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	@Column(name = "QuestionContent")
	public String getQuestionContent() {
		return this.questionContent;
	}

	public void setQuestionContent(String questionContent) {
		this.questionContent = questionContent;
	}

	@Column(name = "Option1Name")
	public String getOption1name() {
		return this.option1name;
	}

	public void setOption1name(String option1name) {
		this.option1name = option1name;
	}

	@Column(name = "Option2Name")
	public String getOption2name() {
		return this.option2name;
	}

	public void setOption2name(String option2name) {
		this.option2name = option2name;
	}

	@Column(name = "isActive")
	public Boolean getIsActive() {
		return this.isActive;
	}

	public void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}

}